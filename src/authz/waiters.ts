import {
  AUTHZ_MAX_CONCURRENT_WAITS,
  type ApprovalStatus,
} from "./types.js";

export interface ApprovalDecision {
  status: Extract<ApprovalStatus, "approved" | "denied" | "expired">;
}

type Waiter = {
  workspaceId: string;
  resolve: (d: ApprovalDecision) => void;
  timer: ReturnType<typeof setTimeout>;
  abortHandler: (() => void) | null;
  signal?: AbortSignal;
};

export class ApprovalWaiterMap {
  private readonly waiters = new Map<string, Waiter>();

  workspacePending(workspaceId: string): number {
    let n = 0;
    for (const w of this.waiters.values()) {
      if (w.workspaceId === workspaceId) n += 1;
    }
    return n;
  }

  atCap(workspaceId: string): boolean {
    return this.workspacePending(workspaceId) >= AUTHZ_MAX_CONCURRENT_WAITS;
  }

  wait(
    approvalId: string,
    opts: {
      workspaceId: string;
      timeoutMs: number;
      signal?: AbortSignal;
      onTimeout?: () => void;
      onAbort?: () => void;
    },
  ): Promise<ApprovalDecision> {
    return new Promise((resolve) => {
      const finish = (d: ApprovalDecision) => {
        const w = this.waiters.get(approvalId);
        if (!w) return;
        clearTimeout(w.timer);
        if (w.signal && w.abortHandler) {
          w.signal.removeEventListener("abort", w.abortHandler);
        }
        this.waiters.delete(approvalId);
        resolve(d);
      };

      const abortHandler = () => {
        opts.onAbort?.();
        finish({ status: "expired" });
      };

      const timer = setTimeout(() => {
        opts.onTimeout?.();
        finish({ status: "expired" });
      }, Math.max(1, opts.timeoutMs));

      if (opts.signal?.aborted) {
        clearTimeout(timer);
        opts.onAbort?.();
        resolve({ status: "expired" });
        return;
      }

      const waiter: Waiter = {
        workspaceId: opts.workspaceId,
        resolve: finish,
        timer,
        abortHandler: opts.signal ? abortHandler : null,
        signal: opts.signal,
      };
      this.waiters.set(approvalId, waiter);
      opts.signal?.addEventListener("abort", abortHandler, { once: true });
    });
  }

  /** Unblock a waiting tools/call. Returns false if no waiter (already timed out). */
  resolve(approvalId: string, status: "approved" | "denied"): boolean {
    const w = this.waiters.get(approvalId);
    if (!w) return false;
    w.resolve({ status });
    return true;
  }
}

export const globalApprovalWaiters = new ApprovalWaiterMap();
