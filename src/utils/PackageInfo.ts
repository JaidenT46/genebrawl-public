import {Libc} from "../libs/Libc";
import {LogicVersion} from "../logic/LogicVersion";
import ObjC from "frida-objc-bridge";

const VALID_PACKAGE_NAMES_FOR_ENVIRONMENT: { [environment: string]: string[]; } = {
    "dev": [
        "gene.brawl.dev",
        "gene.brawl.vip",
        "gene.brawl.release",
        "com.supercell.brawlstars",
        "com.supercell.brawlstarts",
        "bsd.suitcase.release"
    ],

    "vip": [
        "gene.brawl.dev",
        "gene.brawl.vip"
    ],

    "free": [
        "gene.brawl.release"
    ]
};

export class PackageInfo {
    static isPackageNameValid(name: string): boolean {
        let scriptEnvironment = LogicVersion.scriptEnvironment;

        if (!VALID_PACKAGE_NAMES_FOR_ENVIRONMENT[scriptEnvironment].includes(name)) {
            console.error(`Package name ${name} is invalid in ${scriptEnvironment} environment.`);
        }


        /// #if DEBUG
        if (LogicVersion.isDeveloperBuild()) // ignore package name in dev build
            return true;
        /// #endif

        return VALID_PACKAGE_NAMES_FOR_ENVIRONMENT[scriptEnvironment].includes(name);
    }

    static getPackageName(): string | null {
        let fd = Libc.open("/proc/self/cmdline", 0, "r");
        if (fd != -1) {
            let buffer = Libc.malloc(256);
            Libc.read(fd, buffer, 256);
            Libc.close(fd);
            let name = buffer.readUtf8String();
            return this.isPackageNameValid(name!) ? name : "";
        }

        return null;
    }

    static getValue(key: string) {
        if (!ObjC.available) {
            console.error("[PackageInfo]", "getValue:", "ObjC.available is false!!");
            return null;
        }

        const mainBundle = ObjC.classes.NSBundle.mainBundle();
        const infoDict = mainBundle.infoDictionary();

        const keyString = ObjC.classes.NSString.stringWithString_(key);
        const value = infoDict.objectForKey_(keyString);

        return value ? value : null;
    }

    static getBundleIdentifier(): string {
        if (ObjC.available) {
            const mainBundle = ObjC.classes.NSBundle.mainBundle();
            return mainBundle.bundleIdentifier();
        } else {
            console.error("Objective-C runtime is not available!");
            return "com.supercell.laser";
        }
    }
}