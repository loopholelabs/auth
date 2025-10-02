import type {ReactNode} from "react";
import {NuqsAdapter} from 'nuqs/adapters/next/app'

export function RootProvider({children}: { children: ReactNode }) {
    return (
        <NuqsAdapter>
            {children}
        </NuqsAdapter>
    );
}