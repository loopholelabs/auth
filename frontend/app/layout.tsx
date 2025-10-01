import type {ReactNode} from "react";

import localFont from 'next/font/local';
import {Inter} from 'next/font/google';

import {RootProvider} from "@/app/providers";

import "./globals.css";
import {ThemeProvider} from "next-themes";

const commitMonoFont = localFont({
    display: 'swap',
    preload: true,
    adjustFontFallback: false,
    variable: '--font-commit-mono',
    src: [
        {
            path: 'commit-mono-variable.woff2',
            weight: '200',
            style: 'normal',
        },
        {
            path: 'commit-mono-variable.woff2',
            weight: '300',
            style: 'normal',
        },
        {
            path: 'commit-mono-variable.woff2',
            weight: '400',
            style: 'normal',
        },
        {
            path: 'commit-mono-variable.woff2',
            weight: '500',
            style: 'normal',
        },
        {
            path: 'commit-mono-variable.woff2',
            weight: '200',
            style: 'italic',
        },
        {
            path: 'commit-mono-variable.woff2',
            weight: '300',
            style: 'italic',
        },
        {
            path: 'commit-mono-variable.woff2',
            weight: '400',
            style: 'italic',
        },
        {
            path: 'commit-mono-variable.woff2',
            weight: '500',
            style: 'italic',
        }
    ],
});
const commitMonoNerdFont = localFont({
    display: 'swap',
    preload: true,
    adjustFontFallback: false,
    variable: '--font-commit-mono-nerd',
    src: [
        {
            path: 'commit-mono-nerd-propo.woff2',
            weight: '300',
            style: 'normal',
        },
    ],
});
const interFont = Inter({
    display: 'fallback',
    preload: true,
    adjustFontFallback: true,
    variable: '--font-inter',
    subsets: ['latin'],
    weight: ['300', '400', '500'],
    style: ['normal', 'italic'],
});

export default function RootLayout({children}: Readonly<{ children: ReactNode }>) {
    return (
        <html lang="en" suppressHydrationWarning={true}>
        <body
            className={`${commitMonoFont.variable} ${interFont.variable} ${commitMonoNerdFont.variable} antialiased min-h-screen min-w-screen`}>
        <ThemeProvider defaultTheme={'dark'} attribute={'class'} enableColorScheme={true}>
            <RootProvider>
                {children}
            </RootProvider>
        </ThemeProvider>
        </body>
        </html>
    );
}