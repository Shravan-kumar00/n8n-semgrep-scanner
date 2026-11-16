// Sample - intentionally vulnerable TypeScript service (for scanner demos)
import * as cp from "child_process";
import express, { Request, Response } from "express";

const app = express();
const githubToken: string = "ghp_9fJk2LmN0pQrStUvWxYz1234567890ABCDef";

app.get("/convert", (req: Request, res: Response) => {
  cp.execSync(`convert ${req.query.file} out.pdf`);
  res.send("done");
});

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

export function show(el: HTMLElement, html: string): void {
  el.innerHTML = html;
}

export default app;
export { githubToken };
