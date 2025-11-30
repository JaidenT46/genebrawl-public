const path = require('path');
const webpack = require("webpack");
const TerserPlugin = require("terser-webpack-plugin");
const WebpackObfuscatorPlugin = require("webpack-obfuscator");
const fs = require("node:fs");

module.exports = function (env, argv) {
    const debug = Boolean(argv.mode === 'development');

    let scriptEnvironment = env['script'];

    console.log("Script environment: " + scriptEnvironment);

    // define preprocessor variables
    const opts = {
        DEBUG: scriptEnvironment === "dev",
        VIP: scriptEnvironment === "vip" || scriptEnvironment === "dev",
        version: 3,
        "ifdef-verbose": true,
        "ifdef-triple-slash": true,
        "ifdef-fill-with-blanks": true,
        "ifdef-uncomment-prefix": "// #code "
    };

    let plugins = [];

    plugins.push(new webpack.DefinePlugin({
        "process.env.SCRIPT_ENV": `"${scriptEnvironment}"`
    }));

    plugins.push(new webpack.ProvidePlugin({
        process: "process/browser",
        Buffer: ["buffer", "Buffer"],
    }));

    if (scriptEnvironment !== "dev") {
        let obfuscatorConfig = JSON.parse(fs.readFileSync("obfuscator.json").toString("utf-8"));

        plugins.push(new WebpackObfuscatorPlugin(
            obfuscatorConfig
        ));
    }

    return {
        entry: './src/index.ts',
        module: {
            rules: [
                {
                    test: /\.tsx?$/,
                    exclude: /node_modules/,
                    use: [
                        { loader: "ts-loader" },
                        { loader: "ifdef-loader", options: opts }
                    ]
                },
            ],
        },
        resolve: {
            extensions: ['.tsx', '.ts', '.js'],
            fallback: {},
        },
        output: {
            filename: 'bundle.js',
            path: path.resolve(__dirname, 'dist'),
            sourceMapFilename: "bundle.js.map"
        },
        optimization: {
            usedExports: true,
            minimize: !debug,
            minimizer: !debug ?

                [new TerserPlugin(
                    {
                        terserOptions: {
                            format: {
                                comments: false,
                            },
                            compress: {
                                drop_console: true,
                                dead_code: true
                            }
                        },
                        extractComments: false,
                    }
                )]

                : [],
        },
        devtool: debug ? 'source-map' : false,
        stats: {
            errorStack: false
        },
        plugins: plugins,
        performance: {
            maxAssetSize: 5 * 1024 * 1024,
            maxEntrypointSize: 5 * 1024 * 1024
        }
    };
};
