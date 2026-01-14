//! Unit tests for the public libkrun C API.
//!
//! Verifies some basic API behavior (ABI, error codes, etc.) without starting actual VMs.

use crate::*;

#[test]
#[cfg(feature = "gpu")]
fn test_display_backend_abi_compatibility() {
    use krun_display::*;

    // This test verifies that old applications compiled against the basic_framebuffer-only
    // version (V1 ABI) can still pass their smaller DisplayBackend struct to the new libkrun
    // that supports dmabuf (V2 ABI).

    unsafe extern "C" fn dummy_disable_scanout(_instance: *mut c_void, _scanout_id: u32) -> i32 {
        DisplayBackendError::InternalError as _
    }

    unsafe extern "C" fn dummy_configure_scanout(
        _instance: *mut c_void,
        _scanout_id: u32,
        _display_width: u32,
        _display_height: u32,
        _width: u32,
        _height: u32,
        _format: u32,
    ) -> i32 {
        DisplayBackendError::InternalError as _
    }

    unsafe extern "C" fn dummy_alloc_frame(
        _instance: *mut c_void,
        _scanout_id: u32,
        _buffer: *mut *mut u8,
        _buffer_size: *mut usize,
    ) -> i32 {
        DisplayBackendError::InternalError as _
    }

    unsafe extern "C" fn dummy_present_frame(
        _instance: *mut c_void,
        _scanout_id: u32,
        _frame_id: u32,
        _rect: *const krun_display::header::krun_rect,
    ) -> i32 {
        DisplayBackendError::InternalError as _
    }

    unsafe {
        let v1_size = size_of::<DisplayBackendV1>();
        let v2_size = size_of::<krun_display::header::krun_display_backend>();

        // Test 1: V1 ABI with basic_framebuffer only (smaller size)
        // Create a properly structured V1 backend
        let v1_backend = DisplayBackendV1 {
            features: DisplayFeatures::BASIC_FRAMEBUFFER.bits(),
            create_userdata: std::ptr::null(),
            create: None,
            vtable: DisplayVtableV1 {
                basic_framebuffer: DisplayBasicFramebufferVtable {
                    destroy: None,
                    disable_scanout: Some(dummy_disable_scanout),
                    configure_scanout: Some(dummy_configure_scanout),
                    alloc_frame: Some(dummy_alloc_frame),
                    present_frame: Some(dummy_present_frame),
                },
            },
        };

        // Create a context for testing
        krun_set_log_level(0);
        let ctx: u32 = krun_create_ctx();
        assert!(ctx > 0, "Failed to create context");

        // This should succeed with the V1 (old, smaller) size
        let result =
            krun_set_display_backend(ctx, &v1_backend as *const _ as *const c_void, v1_size);

        assert_eq!(
            result, 0,
            "V1 ABI test failed: krun_set_display_backend returned {result}",
        );

        // Test 2: V2 ABI with full DisplayBackend structure (current size)
        let ctx2: u32 = krun_create_ctx();
        assert!(ctx2 > 0, "Failed to create second context");

        let mut v2_backend: krun_display::header::krun_display_backend = std::mem::zeroed();
        v2_backend.features = DisplayFeatures::BASIC_FRAMEBUFFER.bits();
        v2_backend.create_userdata = std::ptr::null_mut();
        v2_backend.create = None;

        // Set the basic_framebuffer vtable
        v2_backend.vtable.basic_framebuffer.destroy = None;
        v2_backend.vtable.basic_framebuffer.disable_scanout = Some(dummy_disable_scanout);
        v2_backend.vtable.basic_framebuffer.configure_scanout = Some(dummy_configure_scanout);
        v2_backend.vtable.basic_framebuffer.alloc_frame = Some(dummy_alloc_frame);
        v2_backend.vtable.basic_framebuffer.present_frame = Some(dummy_present_frame);

        // This should also succeed with the V2 (new, larger) size
        let result =
            krun_set_display_backend(ctx2, &v2_backend as *const _ as *const c_void, v2_size);

        assert_eq!(
            result, 0,
            "V2 ABI test failed: krun_set_display_backend returned {result}",
        );
    }
}
