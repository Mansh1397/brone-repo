export interface Env {
    EDGE_SECRET_HMAC: string;
    ORIGIN_URL?: string;
}
declare const _default: {
    fetch(request: Request, env: Env, ctx: any): Promise<Response>;
};
export default _default;
