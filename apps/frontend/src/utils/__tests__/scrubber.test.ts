import { purgeUint8Array, purgeSensitiveObject } from '../scrubber';

describe('Memory-Scrubbing Utilities Unit Tests', () => {
  
  // Test 1: VERIFY DATA CELL EXTINCTION
  it('should successfully overwrite every single physical cell index in the underlying root buffer layout to exactly 0', () => {
    const rawBuffer = new ArrayBuffer(8);
    const typedArray = new Uint8Array(rawBuffer);
    
    // Seed initial data
    typedArray.set([12, 34, 56, 78, 90, 12, 34, 56]);

    // Verify initial state
    expect(typedArray[0]).toBe(12);
    
    // Perform purge
    purgeUint8Array(typedArray);

    // Verify view is zeroed
    for (let i = 0; i < typedArray.length; i++) {
      expect(typedArray[i]).toBe(0);
    }

    // Verify underlying root buffer itself is zeroed by creating a new view
    const newView = new Uint8Array(rawBuffer);
    for (let i = 0; i < newView.length; i++) {
      expect(newView[i]).toBe(0);
    }
  });

  it('should zero out a sliced view within a larger ArrayBuffer', () => {
    const rawBuffer = new ArrayBuffer(16);
    const fullArray = new Uint8Array(rawBuffer);
    fullArray.fill(99);

    // Create a sliced view starting at offset 4 with length 8
    const sliceArray = new Uint8Array(rawBuffer, 4, 8);

    // Purge the slice only
    purgeUint8Array(sliceArray);

    // Verify the slice is zeroed
    for (let i = 0; i < sliceArray.length; i++) {
      expect(sliceArray[i]).toBe(0);
    }

    // Verify the surrounding parts of the original buffer are untouched
    expect(fullArray[0]).toBe(99);
    expect(fullArray[3]).toBe(99);
    expect(fullArray[4]).toBe(0); // slice start
    expect(fullArray[11]).toBe(0); // slice end
    expect(fullArray[12]).toBe(99);
  });

  // Test 2: DEEP OBJECT RECURSION CHECK
  it('should deeply traverse the object, zero out raw binary byte fields at root, and strip properties', () => {
    const secretBytes = new Uint8Array([5, 10, 15, 20]);
    const nestedSecretBytes = new Uint8Array([100, 200]);

    const testObject: any = {
      secretData: secretBytes,
      metadata: {
        version: 'v2.1',
        nestedSecret: nestedSecretBytes,
        requestId: 9999,
      },
      flag: true,
      label: 'secure-label',
    };

    purgeSensitiveObject(testObject);

    // 1. Assert both Uint8Array structures are completely zeroed at root allocations
    expect(secretBytes[0]).toBe(0);
    expect(secretBytes[3]).toBe(0);
    expect(nestedSecretBytes[0]).toBe(0);
    expect(nestedSecretBytes[1]).toBe(0);

    // 2. Assert properties have been deleted/stripped from the root object
    expect(testObject.secretData).toBeUndefined();
    expect(testObject.label).toBeUndefined();
    expect(testObject.flag).toBeUndefined();
    
    // 3. Assert the nested object metadata was recursively stripped and removed
    expect(testObject.metadata).toBeUndefined();
  });

  // Test 3: ROBUST EXCEPTION IMMUNITY
  it('should process edge cases and abnormal parameters cleanly without throwing runtime exceptions', () => {
    // Empty array
    expect(() => purgeUint8Array(new Uint8Array(0))).not.toThrow();

    // Null and undefined
    expect(() => purgeUint8Array(null)).not.toThrow();
    expect(() => purgeUint8Array(undefined as any)).not.toThrow();

    expect(() => purgeSensitiveObject(null)).not.toThrow();
    expect(() => purgeSensitiveObject(undefined)).not.toThrow();

    // Plain objects with no fields
    expect(() => purgeSensitiveObject({})).not.toThrow();
    expect(() => purgeSensitiveObject([])).not.toThrow();

    // Circular references
    const circularObj: any = { name: 'circular-test' };
    circularObj.self = circularObj;
    expect(() => purgeSensitiveObject(circularObj)).not.toThrow();
    // After scrubbing, the fields of circularObj (including self and name) should be deleted
    expect(circularObj.name).toBeUndefined();
    expect(circularObj.self).toBeUndefined();
  });
});
