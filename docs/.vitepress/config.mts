import { execSync } from "node:child_process";
import { resolve } from "node:path";
import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";

const version = execSync("git describe --tags --abbrev=0").toString().trim();
const releaseUrl =
  `https://github.com/davidolrik/keyhole/releases/tag/${version}`;

// https://vitepress.dev/reference/site-config
export default withMermaid(
  defineConfig({
    title: "Keyhole",
    description: "SSH-based secret manager",
    head: [["link", { rel: "icon", href: "/keyhole.png" }]],
    appearance: "force-dark",
    themeConfig: {
      logo: "/keyhole.png",
      // https://vitepress.dev/reference/default-theme-config
      nav: [
        { text: "Home", link: "/" },
        { text: "Getting Started", link: "/getting-started/" },
        { text: "Guide", link: "/guide/configuration" },
        { text: "Reference", link: "/reference/commands" },
        { text: "Security", link: "/security/encryption" },
        { text: version, link: releaseUrl },
      ],

      sidebar: [
        {
          text: "Getting Started",
          items: [
            { text: "Overview", link: "/getting-started/" },
            { text: "Installation", link: "/getting-started/installation" },
            { text: "Server Setup", link: "/getting-started/server-setup" },
          ],
        },
        {
          text: "Guide",
          items: [
            { text: "Configuration", link: "/guide/configuration" },
            { text: "Secrets", link: "/guide/secrets" },
            { text: "Vaults", link: "/guide/vaults" },
            { text: "Invites", link: "/guide/invites" },
            { text: "Colors", link: "/guide/colors" },
          ],
        },
        {
          text: "Reference",
          items: [
            { text: "Commands", link: "/reference/commands" },
            { text: "Data Layout", link: "/reference/data-layout" },
            { text: "Audit Log", link: "/reference/audit-log" },
          ],
        },
        {
          text: "Security",
          items: [
            { text: "Encryption", link: "/security/encryption" },
            { text: "Security Notes", link: "/security/notes" },
          ],
        },
      ],

      socialLinks: [
        { icon: "github", link: "https://github.com/davidolrik/keyhole" },
      ],
    },
  }),
);
