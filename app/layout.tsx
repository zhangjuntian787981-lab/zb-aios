import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";

const title = "多企业 AI 平台产品进度中心";
const description =
  "P0-P2 使用合成数据建设通用产品，P3 才接入目标企业；阶段只由外部产品所有者审批。";

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host =
    requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host");
  const protocol = requestHeaders.get("x-forwarded-proto") ?? "https";
  const metadataBase = host
    ? new URL(`${protocol}://${host}`)
    : new URL("https://zhongbao-ai-progress.zhangjuntian787981.chatgpt.site");

  return {
    metadataBase,
    title,
    description,
    icons: {
      icon: "/favicon.svg",
    },
    openGraph: {
      title,
      description,
      images: [{ url: "/og.png", width: 1200, height: 630 }],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: ["/og.png"],
    },
  };
}

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
