import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "SentinelFlow | Security Operations", description: "Authorized application security testing dashboard" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
