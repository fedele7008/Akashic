/**
 * JSX/IntrinsicElements declarations for the Akashic Web Component
 * widgets. Lets TypeScript accept `<akashic-signup>` etc. as valid
 * JSX in React.
 *
 * Declared on both `React.JSX.IntrinsicElements` (React 19+ where the
 * namespace lives under React) and the legacy global `JSX` (older
 * React, some tooling). Belt-and-suspenders.
 */

import "react";

type WidgetProps = React.DetailedHTMLProps<
  React.HTMLAttributes<HTMLElement>,
  HTMLElement
> & {
  // Permit any string/boolean attribute (e.g. `editable`,
  // `min-password-length`). Tenants integrating widgets in their own
  // TS codebases can ship more precise declarations if they want.
  [attr: string]: unknown;
};

declare module "react" {
  namespace JSX {
    interface IntrinsicElements {
      "akashic-signup": WidgetProps;
      "akashic-signin": WidgetProps;
      "akashic-forgot-help": WidgetProps;
      "akashic-profile": WidgetProps;
      "akashic-change-password": WidgetProps;
      "akashic-change-id": WidgetProps;
      "akashic-verify-email-banner": WidgetProps;
      "akashic-clients": WidgetProps;
      "akashic-connected-apps": WidgetProps;
      "akashic-mfa-settings": WidgetProps;
      "akashic-notification-preferences": WidgetProps;
    }
  }
}

declare global {
  namespace JSX {
    interface IntrinsicElements {
      "akashic-signup": WidgetProps;
      "akashic-signin": WidgetProps;
      "akashic-forgot-help": WidgetProps;
      "akashic-profile": WidgetProps;
      "akashic-change-password": WidgetProps;
      "akashic-change-id": WidgetProps;
      "akashic-verify-email-banner": WidgetProps;
      "akashic-clients": WidgetProps;
      "akashic-connected-apps": WidgetProps;
      "akashic-mfa-settings": WidgetProps;
      "akashic-notification-preferences": WidgetProps;
    }
  }
}

export {};
