import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "中宝企业 AI 项目进度中心",
  description: "一页看懂项目正在做什么、等谁确认，以及 OA、U9、BI 的真实接入状态。",
  openGraph: {
    title: "中宝企业 AI 项目进度中心",
    description: "真实进度 · 权限边界 · 分阶段接入",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
