import { test, expect } from "@playwright/test";

test("should load local signin page and verify Google Sign-in doesn't throw auth/unauthorized-domain", async ({ page }) => {
  // Go to the local preview signin page
  await page.goto("http://localhost:4173/signin");

  // Verify the Google sign-in button is present
  const googleBtn = page.locator("button.btn-google");
  await expect(googleBtn).toBeVisible();

  // Click the button
  await googleBtn.click();

  // Wait a few seconds
  await page.waitForTimeout(4000);

  // Get all visible text elements
  const pageText = await page.locator("body").innerText();
  console.log("Local Page text after clicking Google button:", pageText);

  // Assert that there is NO "auth/unauthorized-domain" error
  expect(pageText).not.toContain("auth/unauthorized-domain");
  expect(pageText).not.toContain("Google sign-in is currently unavailable");
  
  console.log("Local Verification Passed: No domain errors locally!");
});
