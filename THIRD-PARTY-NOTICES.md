# Third-party notices

The Rust sidecar uses crates recorded exactly in `Cargo.lock`. Release packages
include a machine-readable dependency inventory in `sbom.cdx.json`. Those crates
retain their respective licenses; common license families include MIT,
Apache-2.0, BSD, and Unicode licenses.

The native plugin links against the x64dbg Plugin SDK import libraries and the
Jansson ABI distributed with x64dbg. x64dbg and Jansson retain their respective
copyrights and licenses and are not redistributed by this repository's source
package. The plugin dynamically uses the `jansson.dll` already supplied by the
target x64dbg installation.

Windows system libraries (`bcrypt`, `advapi32`, and `ws2_32` in test utilities)
are supplied by Microsoft Windows and are not redistributed in the package.
