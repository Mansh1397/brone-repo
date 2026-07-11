export interface Env {
    BACKEND_URL: string;
    ORIGIN_SIGNATURE_SECRET: string;
}
declare const _default: {
    fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response>;
};
export default _default;
