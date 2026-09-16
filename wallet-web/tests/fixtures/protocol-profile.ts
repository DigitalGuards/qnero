/** A synthetic profile for mocked WASM workers and chain state. Production
 * reads the complete approved profile from the compiled WASM module. */
export const TEST_PROTOCOL_PROFILE =
  '514e5250524630310100' + '00'.repeat(50) + '0600' + '00'.repeat(130);
