import * as Location from "expo-location";
const BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz";
export function encodeGeohash(latitude: number, longitude: number, precision: number = 4): string {
  let isEven = true;
  let latMin = -90, latMax = 90;
  let lonMin = -180, lonMax = 180;
  let geohash = "";
  let bit = 0;
  let ch = 0;
  while (geohash.length < precision) {
    let mid;
    if (isEven) {
      mid = (lonMin + lonMax) / 2;
      if (longitude > mid) {
        ch |= (1 << (4 - bit));
        lonMin = mid;
      } else {
        lonMax = mid;
      }
    } else {
      mid = (latMin + latMax) / 2;
      if (latitude > mid) {
        ch |= (1 << (4 - bit));
        latMin = mid;
      } else {
        latMax = mid;
      }
    }
    isEven = !isEven;
    if (bit < 4) {
      bit++;
    } else {
      geohash += BASE32[ch];
      bit = 0;
      ch = 0;
    }
  }
  return geohash;
}
export async function resolveCoarseMacroRegion(): Promise<string> {
  const { status } = await Location.requestForegroundPermissionsAsync();
  if (status !== "granted") {
    throw new Error("PERMISSION_DENIED");
  }
  // Enforce coarse accuracy corresponding to Low accuracy (approx nearest kilometer)
  const location = await Location.getCurrentPositionAsync({
    accuracy: 2 // Low accuracy
  });
  if (!location || !location.coords) {
    throw new Error("LOCATION_RESOLUTION_FAILED");
  }
  const { latitude, longitude } = location.coords;
  // Convert fuzzy coordinates locally into a unique global cell ID string
  const cellId = "cell_gh_" + encodeGeohash(latitude, longitude, 4);
  // Raw coordinates are instantly discarded by exiting the scope
  return cellId;
}