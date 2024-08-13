#![no_std]

use libtock_platform as platform;
use libtock_platform::allow_ro::AllowRo;
use libtock_platform::share;
use libtock_platform::{
    return_variant, syscall_class, DefaultConfig, ErrorCode, Register, ReturnVariant, Syscalls,
};

/// The IPC API provides ...

pub struct Ipc<S: Syscalls, C: Config = DefaultConfig>(S, C);

static mut EMPTY_BUF: [u8; 0] = [];

impl<S: Syscalls, C: Config> Ipc<S, C> {
    /// Run a check against the IPC driver to ensure it is present.
    ///
    /// Returns `true` if the driver was present.
    #[inline(always)]
    pub fn exists() -> bool {
        S::command(DRIVER_NUM, command::EXISTS, 0, 0).is_success()
    }

    /// Discover the a service by its package name.
    ///
    /// Returns the service ID as a `u32`.
    pub fn discover(pkg_name: &str) -> Result<u32, ErrorCode> {
        share::scope::<(AllowRo<_, DRIVER_NUM, { allow_ro::SEARCH }>,), _, _>(|handle| {
            let (allow,) = handle.split();
            S::allow_ro::<C, DRIVER_NUM, { allow_ro::SEARCH }>(allow, pkg_name.as_bytes())?;
            S::command(DRIVER_NUM, command::DISCOVER, 0, 0).to_result()
        })
    }

    /// Register a callback for a service.
    pub fn register<CB: IpcCallback>(svc_id: u32, cb: &CB) -> Result<(), ErrorCode> {
        // The upcall function passed to the Tock kernel.
        //
        // Safety: cbptr must be a reference to a valid instance of CB.
        unsafe extern "C" fn kernel_upcall<S: Syscalls, CB: IpcCallback>(
            target: u32,
            len: u32,
            ptr: Register,
            cbptr: Register,
        ) {
            let upcall: *mut CB = cbptr.into();
            unsafe {
                let data = if ptr.as_u32() != 0 {
                    // Valid pointer, create a slice.
                    core::slice::from_raw_parts_mut(ptr.0 as *mut u8, len as usize)
                } else {
                    // Null pointer, use the empty slice.
                    &mut EMPTY_BUF
                };
                (&mut *upcall).call(target, data);
            }
        }

        let upcall = (kernel_upcall::<S, CB> as *const ());
        let cbptr = (cb as *const CB);

        // We use the low-level syscall interface because the higher-level syscall
        // wrappers are geared towards building synchronous APIs for drivers.
        // IPC notifications don't necessarily follow the same model.
        //
        // Furthermore, the higher-level syscall wrappers encode the subsribe ID
        // as a constant type parameter, but the IPC driver uses the service ID
        // (aka pid) to identify to which process we're attaching the upcall.
        //
        // Safety: upcall must be kernel_upcall<S, CB> and cbptr must be a pointer
        // to a valid CB object.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                DRIVER_NUM.into(),
                svc_id.into(),
                upcall.into(),
                cbptr.into(),
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
        Ok(())
    }

    /// Send a notification to a service, causing the registered callback to
    /// execute in that service.
    pub fn notify_service(svc_id: u32) -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, command::NOTIFY_SERVICE, svc_id, 0).to_result()
    }

    /// Send a notification to a client, causing the registered callback to
    /// execute in that client.
    pub fn notify_client(svc_id: u32) -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, command::NOTIFY_CLIENT, svc_id, 0).to_result()
    }

    /// Share a buffer with another process.
    pub fn share(svc_id: u32, buf: &'static mut [u8]) -> Result<(), ErrorCode> {
        let ptr = buf.as_ptr();
        let len = buf.len();
        // We use the low-level syscall interface because the higher-level syscall
        // wrappers are geared towards building synchronous APIs for drivers.
        // IPC notifications don't necessarily follow the same model.
        //
        // Furthermore, the higher-level syscall wrappers encode the share ID
        // as a constant type parameter, but the IPC driver uses the service ID
        // (aka pid) to identify to which process we're sharing the buffer.
        //
        // Safety: ptr and len are valid components of a slice.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RW }>([
                DRIVER_NUM.into(),
                svc_id.into(),
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
        Ok(())
    }
}

pub trait IpcCallback {
    fn call(&mut self, pid: u32, buf: &'static mut [u8]);
}

pub trait Config: platform::allow_ro::Config {}

impl<T: platform::allow_ro::Config> Config for T {}

//#[cfg(test)]
//mod tests;

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

const DRIVER_NUM: u32 = 0x10000;

mod command {
    pub const EXISTS: u32 = 0;
    pub const DISCOVER: u32 = 1;
    pub const NOTIFY_SERVICE: u32 = 2;
    pub const NOTIFY_CLIENT: u32 = 3;
}

mod allow_ro {
    pub const SEARCH: u32 = 0;
}
