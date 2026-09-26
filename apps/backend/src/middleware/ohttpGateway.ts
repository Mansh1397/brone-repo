import { Request, Response, NextFunction } from 'express';
import * as net from 'net';

const ENCLAVE_VSOCK_CID = 16;
const ENCLAVE_VSOCK_PORT = 5000;

/**
 * Dumb Proxy Express Middleware (Phase 3 Architecture)
 * 
 * Eradicates host-level cryptography from Node.js runtime:
 * - Performs NO OHTTP decapsulation, NO padding stripping, NO setTimeout chaff delays in Node.js heap.
 * - Ingests the 2MB binary payload and streams it directly over vsock (CID 16, Port 5000) to AWS Nitro Enclave.
 * - Streams the Enclave response buffer directly back to the client/OHTTP Relayer.
 */
export async function ohttpGatewayMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.headers['content-type'] !== 'application/ohttp-req') {
    return next();
  }

  try {
    const rawBodyBuf: Buffer = req.body && Buffer.isBuffer(req.body) ? req.body : (req as any).rawBody;

    if (!rawBodyBuf || rawBodyBuf.length === 0) {
      res.setHeader('Content-Type', 'application/ohttp-res');
      return res.status(400).send(Buffer.from('Invalid OHTTP Request Body'));
    }

    // Connect to AWS Nitro Enclave vsock stream socket (CID 16, Port 5000)
    // Note: In Node.js environment under Linux/Nitro, vsock sockets use socket connections via AF_VSOCK or TCP proxy bridge
    const vsockSocket = net.connect({
      port: ENCLAVE_VSOCK_PORT,
      host: process.env.VSOCK_BRIDGE_HOST || '127.0.0.1'
    });

    const responseChunks: Buffer[] = [];

    vsockSocket.on('connect', () => {
      // Stream raw 2MB payload directly to Nitro Enclave
      vsockSocket.write(rawBodyBuf);
      vsockSocket.end();
    });

    vsockSocket.on('data', (chunk: Buffer) => {
      responseChunks.push(chunk);
    });

    vsockSocket.on('end', () => {
      const enclaveResponse = Buffer.concat(responseChunks);
      res.setHeader('Content-Type', 'application/ohttp-res');
      res.status(200).send(enclaveResponse);
    });

    vsockSocket.on('error', (vsockErr: Error) => {
      console.error("[VSOCK PROXY ERROR] Failed streaming to Nitro Enclave:", vsockErr.message);
      res.setHeader('Content-Type', 'application/ohttp-res');
      res.status(502).send(Buffer.from('Nitro Enclave Gateway Unreachable'));
    });

  } catch (err: any) {
    console.error("[DUMB PROXY ERROR] Stream error:", err.message || err);
    res.setHeader('Content-Type', 'application/ohttp-res');
    res.status(500).send(Buffer.from('Gateway Streaming Failure'));
  }
}
