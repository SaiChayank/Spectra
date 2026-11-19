import { motion } from "motion/react";
import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { SkewButton } from "./controls";

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

/** Focus trap + Escape + focus restore, shared by Modal and Drawer. */
function useDialog(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  });
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const el = ref.current;
    (el?.querySelector<HTMLElement>("[data-autofocus]") ?? el?.querySelector<HTMLElement>(FOCUSABLE) ?? el)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        close.current();
        return;
      }
      if (e.key !== "Tab" || !el) return;
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      previous?.focus?.();
    };
  }, [open]);
  return ref;
}

function Portal({ children }: { children: ReactNode }) {
  // render inside the nearest .sx root so tokens apply
  const host = document.querySelector(".sx") ?? document.body;
  return createPortal(children, host);
}

export function Modal({
  open,
  onClose,
  title,
  children,
  actions,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
}) {
  const ref = useDialog(open, onClose);
  const id = useId();
  if (!open) return null;
  return (
    <Portal>
      <motion.div className="sx-scrim" onClick={onClose} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2 }} />
      <motion.div
        ref={ref}
        className="sx-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={id}
        tabIndex={-1}
        initial={{ opacity: 0, scale: 0.96, x: "-50%", y: "-46%" }}
        animate={{ opacity: 1, scale: 1, x: "-50%", y: "-50%" }}
        transition={{ type: "spring", stiffness: 380, damping: 32 }}
      >
        <div className="sx-overlay-head">
          <h2 id={id} style={{ fontSize: 20 }}>
            {title}
          </h2>
          <button type="button" className="sx-close" aria-label="Close" onClick={onClose}>
            ×
          </button>
        </div>
        {children}
        {actions ? <div className="sx-overlay-actions">{actions}</div> : null}
      </motion.div>
    </Portal>
  );
}

/**
 * Confirmation for actions that change what the system does. The consequence
 * is spelled out, and Cancel has focus by default.
 */
export function ConfirmDialog({
  open,
  title,
  consequence,
  confirmLabel,
  danger,
  busy,
  onConfirm,
  onCancel,
  children,
}: {
  open: boolean;
  title: string;
  consequence: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ReactNode;
}) {
  return (
    <Modal
      open={open}
      onClose={onCancel}
      title={title}
      actions={
        <>
          <SkewButton variant="ghost" onClick={onCancel} data-autofocus>
            Cancel
          </SkewButton>
          <SkewButton variant={danger ? "danger" : "primary"} loading={busy} onClick={onConfirm}>
            {confirmLabel}
          </SkewButton>
        </>
      }
    >
      {children}
      <p className="sx-consequence">
        <strong>What happens: </strong>
        {consequence}
      </p>
    </Modal>
  );
}

export function Drawer({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children?: ReactNode;
}) {
  const ref = useDialog(open, onClose);
  const id = useId();
  if (!open) return null;
  return (
    <Portal>
      <motion.div className="sx-scrim" onClick={onClose} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2 }} />
      <motion.aside
        ref={ref}
        className="sx-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={id}
        tabIndex={-1}
        initial={{ x: 48, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ type: "spring", stiffness: 340, damping: 34 }}
      >
        <div className="sx-overlay-head">
          <h2 id={id} style={{ fontSize: 20 }}>
            {title}
          </h2>
          <button type="button" className="sx-close" aria-label="Close" onClick={onClose}>
            ×
          </button>
        </div>
        {children}
      </motion.aside>
    </Portal>
  );
}
