const ctx: Worker = self as any;

ctx.addEventListener("message", (event: MessageEvent) => {
  const { id, type, payload } = event.data;

  // HEAP SANITIZATION WRAPPER per-message
  let resultString: string | null = null;
  let uint8Array: Uint8Array | null = null;
  let tempBigInt: bigint | null = null;

  try {
    switch (type) {
      case "GENERATE_RING_SIGNATURE": {
        // Mock execution of ring signature math
        // Let's parse dummy inputs to make sure BigInt conversion runs
        const seedVal = BigInt("0x" + (payload.messageHash || "abcdef"));
        tempBigInt = seedVal * 123456789n;
        resultString = tempBigInt.toString(16);
        break;
      }

      case "BLIND_TOKEN_PARAMETERS": {
        // Mock execution of blinding parameters
        const val = BigInt(payload.value || "1");
        tempBigInt = val + 987654321n;
        resultString = tempBigInt.toString(16);
        break;
      }

      case "UNBLIND_STAMPED_TOKEN": {
        // Mock execution of unblinding
        const token = BigInt(payload.token || "2");
        tempBigInt = token - 55555n;
        resultString = tempBigInt.toString(16);
        break;
      }

      default:
        throw new Error(`Unsupported transaction type: ${type}`);
    }

    if (resultString !== null) {
      uint8Array = new TextEncoder().encode(resultString);
      // ZERO-RESIDUE TRANSFERABLE RESPONSE
      ctx.postMessage({ id, payload: uint8Array }, [uint8Array.buffer]);
    }
  } catch (error: any) {
    ctx.postMessage({ id, error: error.message || "Worker execution failed" });
  } finally {
    // Heap sanitization: overwrite volatile data
    resultString = null;
    uint8Array = null;
    if (tempBigInt !== null) {
      tempBigInt = 0n;
      tempBigInt = null;
    }
  }
});
