import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "007 | Security Operations", description: "Authorized security operations, scanning, and human review workspace" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
