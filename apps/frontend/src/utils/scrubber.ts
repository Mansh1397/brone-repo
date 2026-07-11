/**
 * ============================================================================
 * COMPLIANCE STANDARD WARNING:
 * High-sensitivity cryptographic data variables (such as blinding parameters, 
 * private keys, handshakes, and moving tokens) MUST remain stored as raw 
 * Uint8Array bytes throughout their execution lifecycle rather than being cast 
 * or passed around as standard JavaScript strings. 
 *
 * Because JavaScript strings are immutable, any string conversions or operations
 * create transient copies in the V8 engine heap that cannot be cleared or zeroed
 * in-place. Storing secrets in raw Uint8Arrays allows direct, low-level in-place
 * byte zeroing, neutralizing the JavaScript string immutability exposure window.
 * ============================================================================
 */

/**
 * 1. ROOT BUFFER HARDWARE PURGE
 * Synchronously and forcefully overwrites the underlying ArrayBuffer memory
 * page and the view itself with exactly 0.
 *
 * @param array The Uint8Array to purge.
 */
export function purgeUint8Array(array: Uint8Array | null): void {
  if (!array) {
    return;
  }

  try {
    const buffer = array.buffer;
    // Instantiate a DataView mapping over the target offset and length
    const view = new DataView(buffer, array.byteOffset, array.byteLength);
    
    // Forcefully overwrite raw physical bytes with 0
    for (let i = 0; i < array.byteLength; i++) {
      view.setUint8(i, 0);
    }
  } catch (e) {
    // Fallback if DataView or buffer access fails on anomalous objects
  }

  // Compounding sweep: fill the view itself to clean view state
  try {
    array.fill(0);
  } catch (e) {
    // Ignore if array is read-only or frozen
  }
}

/**
 * 2. DESTRUCTIVE DEEP CONTEXT CLEANER
 * Recursively inspects target objects, zeroing out Uint8Arrays and removing/nullifying
 * sensitive properties to trigger immediate V8 garbage collection reclamation.
 *
 * @param obj The target object to clean.
 * @param visited Track visited objects to avoid infinite recursion on circular graphs.
 */
export function purgeSensitiveObject(obj: any, visited = new WeakSet<any>()): void {
  if (!obj || typeof obj !== 'object') {
    return;
  }

  // Prevent infinite loops on circular references
  if (visited.has(obj)) {
    return;
  }
  visited.add(obj);

  // If the passed object itself is a Uint8Array, purge it
  if (obj instanceof Uint8Array) {
    purgeUint8Array(obj);
    return;
  }

  // Traverse Array-like structures
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const val = obj[i];
      if (val instanceof Uint8Array) {
        purgeUint8Array(val);
        obj[i] = null;
      } else if (val && typeof val === 'object') {
        if (visited.has(val)) {
          obj[i] = null;
        } else {
          purgeSensitiveObject(val, visited);
        }
      } else {
        // Overwrite and nullify strings and other primitive elements in arrays
        obj[i] = null;
      }
    }
    return;
  }

  // Traverse object properties
  const keys = Object.keys(obj);
  for (const key of keys) {
    const val = obj[key];

    if (val instanceof Uint8Array) {
      // Zero out the Uint8Array at its root allocation first
      purgeUint8Array(val);
      // Overwrite property reference to null and delete key completely
      obj[key] = null;
      try {
        delete obj[key];
      } catch (e) {}
    } else if (typeof val === 'string') {
      // Overwrite string slot reference to null and delete key
      obj[key] = null;
      try {
        delete obj[key];
      } catch (e) {}
    } else if (val && typeof val === 'object') {
      if (visited.has(val)) {
        // Break the circular reference link immediately
        obj[key] = null;
        try {
          delete obj[key];
        } catch (e) {}
      } else {
        // Recurse into nested structures
        purgeSensitiveObject(val, visited);
        // If the nested object has been stripped down to empty, remove its reference
        if (Object.keys(val).length === 0) {
          obj[key] = null;
          try {
            delete obj[key];
          } catch (e) {}
        }
      }
    } else {
      // Forcefully overwrite other primitives (number, boolean, etc.) and delete keys
      obj[key] = null;
      try {
        delete obj[key];
      } catch (e) {}
    }
  }
}
