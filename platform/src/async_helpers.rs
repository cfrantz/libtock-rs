use crate::subscribe::AnyId;
use crate::{
    return_variant, syscall_class, DefaultConfig, ErrorCode, Register, ReturnVariant, Syscalls,
    Upcall,
};

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// A yield for async implementations.
/// This doesn't actually issue the yield syscall, it yields to the async
/// executor.  The executor is expected to issue the yield syscall.
pub struct Yield {
    ready: bool,
}

impl Yield {
    pub fn now() -> Self {
        Yield { ready: false }
    }
}

impl Future for Yield {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.ready {
            false => {
                self.as_mut().ready = true;
                Poll::Pending
            }
            true => Poll::Ready(()),
        }
    }
}

/// The simplest possible executor for async tasks.
/// A proper executor would take sleeping tasks off of the run queue until
/// they are woken up.  This executor simply loops over the list of tasks
/// and polls them until they return `Ready` (meaning completed).
pub struct Executor<'a, S: Syscalls, const TASKS: usize> {
    task: [Pin<&'a mut dyn Future<Output = ()>>; TASKS],
    done: [bool; TASKS],
    _syscalls: core::marker::PhantomData<S>,
}

impl<'a, S: Syscalls, const TASKS: usize> Executor<'a, S, TASKS> {
    pub fn new(task: [Pin<&'a mut dyn Future<Output = ()>>; TASKS]) -> Executor<S, TASKS> {
        Self {
            task,
            done: [false; TASKS],
            _syscalls: core::marker::PhantomData,
        }
    }

    pub fn run(&mut self, cx: &mut Context<'_>) {
        let mut all_done = 0;
        while all_done != TASKS {
            all_done = 0;
            for i in 0..TASKS {
                if self.done[i] {
                    all_done += 1;
                } else {
                    match self.task[i].as_mut().poll(cx) {
                        Poll::Ready(_) => {
                            self.done[i] = true;
                            all_done += 1;
                        }
                        Poll::Pending => {
                            // Nothing
                        }
                    }
                }
            }
            S::yield_no_wait();
        }
    }
}

/// Share provides an interface to the allow syscalls.  The allow is
/// cancelled when the `Share` goes out of scope.
pub struct Share<'a, S: Syscalls, const SHARE_TYPE: usize> {
    driver_num: u32,
    buffer_num: u32,
    _syscalls: core::marker::PhantomData<S>,
    _data: core::marker::PhantomData<&'a [u8]>,
}

impl<'a, S: Syscalls, const SHARE_TYPE: usize> Share<'a, S, SHARE_TYPE> {
    pub fn new(
        driver_num: u32,
        buffer_num: u32,
        data: &'a [u8],
    ) -> Result<Share<'a, S, SHARE_TYPE>, ErrorCode> {
        let ptr = data.as_ptr();
        let len = data.len();

        // Safety: ptr and len are valid components of a slice.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ SHARE_TYPE }>([
                driver_num.into(),
                buffer_num.into(),
                ptr.into(),
                len.into(),
            ])
        };

        let rv: ReturnVariant = r0.as_u32().into();
        if rv == return_variant::FAILURE_2_U32 {
            // Safety: TRD 104 guarantees that if r0 is Failure with 2 U32,
            // then r1 will contain a valid error code. ErrorCode is
            // designed to be safely transmuted directly from a kernel error
            // code.
            return Err(unsafe { core::mem::transmute(r1.as_u32()) });
        }
        Ok(Self {
            driver_num,
            buffer_num,
            _syscalls: core::marker::PhantomData,
            _data: core::marker::PhantomData,
        })
    }
}

impl<'a, S: Syscalls, const SHARE_TYPE: usize> Drop for Share<'a, S, SHARE_TYPE> {
    fn drop(&mut self) {
        unsafe {
            // Safety: The zero-slice unshares the previously shared buffer.
            S::syscall4::<{ SHARE_TYPE }>([
                self.driver_num.into(),
                self.buffer_num.into(),
                0usize.into(),
                0usize.into(),
            ])
        };
    }
}

type ShareRo<'a, S: Syscalls> = Share<'a, S, { syscall_class::ALLOW_RO }>;
type ShareRw<'a, S: Syscalls> = Share<'a, S, { syscall_class::ALLOW_RW }>;

/// SubscribeUpcall provides subscriptions to upcalls.  The subscription is
/// cancelled when the `Share` goes out of scope.
pub struct SubscribeUpcall<'a, S: Syscalls> {
    driver_num: u32,
    subscribe_num: u32,
    _syscalls: core::marker::PhantomData<S>,
    _upcall: core::marker::PhantomData<&'a dyn Upcall<AnyId>>,
}

impl<'a, S: Syscalls> SubscribeUpcall<'a, S> {
    pub fn new<U: Upcall<AnyId>>(
        driver_num: u32,
        subscribe_num: u32,
        upcall: &'a U,
    ) -> Result<SubscribeUpcall<'a, S>, ErrorCode> {
        unsafe extern "C" fn kernel_upcall<S: Syscalls, U: Upcall<AnyId>>(
            arg0: u32,
            arg1: u32,
            arg2: u32,
            data: Register,
        ) {
            let upcall: *const U = data.into();
            unsafe { &*upcall }.upcall(arg0, arg1, arg2);
        }

        let kup_func = kernel_upcall::<S, U> as *const ();
        let kup_data = upcall as *const U;
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                kup_func.into(),
                kup_data.into(),
            ])
        };

        let rv: ReturnVariant = r0.as_u32().into();
        if rv == return_variant::FAILURE_2_U32 {
            // Safety: TRD 104 guarantees that if r0 is Failure with 2 U32,
            // then r1 will contain a valid error code. ErrorCode is
            // designed to be safely transmuted directly from a kernel error
            // code.
            return Err(unsafe { core::mem::transmute(r1.as_u32()) });
        }
        Ok(Self {
            driver_num,
            subscribe_num,
            _syscalls: core::marker::PhantomData,
            _upcall: core::marker::PhantomData,
        })
    }
}

impl<'a, S: Syscalls> Drop for SubscribeUpcall<'a, S> {
    fn drop(&mut self) {
        unsafe {
            // Safety: The null upcall pointer unsubscribes the previously registered upcall.
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                self.driver_num.into(),
                self.subscribe_num.into(),
                0usize.into(),
                0usize.into(),
            ])
        };
    }
}
