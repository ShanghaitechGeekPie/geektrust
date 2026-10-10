import { useState } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ConfirmDialog";
import { EventsList } from "./EventsList";

it("returns keyboard focus to the activity button after Escape", async () => {
  render(
    <EventsList
      events={[
        { ts: "2026-10-07T00:00:00Z", kind: "login_success", message: "会话已建立" },
      ]}
      dropped={0}
    />,
  );
  const trigger = screen.getByRole("button", { name: "查看全部" });
  trigger.focus();
  fireEvent.click(trigger);
  const dialog = await screen.findByRole("dialog");
  fireEvent.keyDown(dialog, { key: "Escape" });
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await waitFor(() => expect(document.activeElement).toBe(trigger));
});

it("cancels a destructive confirmation without acting and restores focus", async () => {
  const confirm = vi.fn();
  function Example() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <Button onClick={() => setOpen(true)}>注销本机</Button>
        <ConfirmDialog
          open={open}
          onOpenChange={setOpen}
          title="注销本机？"
          description="本机会话将失效。"
          action="注销"
          onConfirm={confirm}
          destructive
        />
      </>
    );
  }
  render(<Example />);
  const trigger = screen.getByRole("button", { name: "注销本机" });
  trigger.focus();
  fireEvent.click(trigger);
  await screen.findByRole("alertdialog");
  fireEvent.click(screen.getByRole("button", { name: "取消" }));
  await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
  expect(confirm).not.toHaveBeenCalled();
  await waitFor(() => expect(document.activeElement).toBe(trigger));
});
