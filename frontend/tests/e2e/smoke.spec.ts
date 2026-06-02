import { test, expect } from "@playwright/test";

test.describe("AgentShield smoke", () => {
  test("loads the public site", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveTitle(/AgentShield/i);
    await expect(page.getByRole("heading", { name: /agent/i }).first()).toBeVisible();
    await expect(page.getByText(/ledger/i).first()).toBeVisible();
  });
});
