import type {NextConfig} from "next";

const nextConfig: NextConfig = {
    output: 'export',
    images: {
        unoptimized: true,
    },
    basePath: '',
};

export default nextConfig;
