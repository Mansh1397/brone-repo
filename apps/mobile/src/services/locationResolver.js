"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.encodeGeohash = encodeGeohash;
exports.resolveCoarseMacroRegion = resolveCoarseMacroRegion;
const Location = __importStar(require("expo-location"));
const BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz";
function encodeGeohash(latitude, longitude, precision = 4) {
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
            }
            else {
                lonMax = mid;
            }
        }
        else {
            mid = (latMin + latMax) / 2;
            if (latitude > mid) {
                ch |= (1 << (4 - bit));
                latMin = mid;
            }
            else {
                latMax = mid;
            }
        }
        isEven = !isEven;
        if (bit < 4) {
            bit++;
        }
        else {
            geohash += BASE32[ch];
            bit = 0;
            ch = 0;
        }
    }
    return geohash;
}
async function resolveCoarseMacroRegion() {
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
