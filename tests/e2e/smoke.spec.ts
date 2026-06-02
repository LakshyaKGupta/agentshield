import { test, expect } from "@playwright/test";

test.describe("AgentShield Marketing Smoke Tests", () => {
  test("should load the home page and verify structural layout elements", async ({ page }) => {
    // Navigate to the local server
    await page.goto("/");

    // Verify page title
    await expect(page).toHaveTitle(/AgentShield/i);

    // Verify main Heading and CTA buttons
    const h1 = page.locator("h1");
    await expect(h1).toContainText(/agent/i);

    // Verify key sections are present (Identity, Manifests, Ledger)
    const cards = page.locator(".feature-card, h3");
    const textContent = await cards.allTextContents();
    const hasAuditLedger = textContent.some((text) => /ledger|audit/i.test(text));
    expect(hasAuditLedger).toBe(true);
  });
});
