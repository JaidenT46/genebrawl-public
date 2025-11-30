import * as fs from 'fs';
import * as path from 'path';
import {LocalizationManager} from "./index";

const keys: string[] = [];

function findLocalizationKeys(directory: string = "../../"): string[] {
    const regex = /LocalizationManager\.getStateString\s*\(\s*["'](.*?)["']\s*,\s*(.*)\s*\)/g;

    const files = fs.readdirSync(directory);

    files.forEach(file => {
        const fullPath = path.join(directory, file);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
            findLocalizationKeys(fullPath);
        } else if (file.endsWith('.ts')) {
            const content = fs.readFileSync(fullPath, 'utf-8');
            let match;
            while ((match = regex.exec(content)) !== null) {
                if (match[1] == "EXAMPLE")
                    continue;

                console.log(`Found match in file: ${fullPath}, key: ${match[1]}`);
                keys.push(match[1]);
            }
        }
    });

    return keys;
}

function main(): void {
    const keys = Object.keys(LocalizationManager.locales);
    const localizationKeys = findLocalizationKeys();

    if (keys.length === 0) {
        console.error("No locales defined.");
        return;
    }

    const missingKeys: { [lang: string]: string[]; } = {};

    keys.forEach((lang) => {
        missingKeys[lang] = [];
        const locale = LocalizationManager.locales[lang];
        if (!locale) {
            console.warn(`Locale for ${lang} is missing in LocalizationManager.`);
            return;
        }

        localizationKeys.forEach((key) => {
            if (!(key + "_ON" in locale)) {
                missingKeys[lang].push(key + "_ON");
            }
            if (!(key + "_OFF" in locale)) {
                missingKeys[lang].push(key + "_OFF");
            }
        });
    });

    Object.entries(missingKeys).forEach(([lang, missing]) => {
        console.warn(`Missing keys in ${lang} (${missing.length}):`);

        missing.forEach((miss) => {
            console.log(`${miss}: "",`);
        });
    });
}

main();