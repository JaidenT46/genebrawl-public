import {Libc} from "../../libs/Libc";
import {Libg} from "../../libs/Libg";
import {LogicDefines} from "../../LogicDefines";
import ObjC from "frida-objc-bridge";

const Application_copyString = new NativeFunction( // TID_DEVICE_LINK_CODE_COPIED
    Libg.offset(0xC005F8, 0xB9B7D0), 'void', ['pointer']
);

export class Application {
    static copyString(str: string) {
        Application_copyString(str.scptr());
    }

    static getDeviceType(): string {
        if (LogicDefines.isPlatformAndroid()) {
            return Libc.getSystemProperty("ro.product.model") || Libc.getSystemProperty("ro.product.name");
        }

        return Libc.sysctlbyname("hw.machine");
    }

    static getSystemVersion(): string {
        if (LogicDefines.isPlatformAndroid()) {
            return Libc.getSystemProperty("ro.build.version.release");
        }

        let processInfo = ObjC.classes.NSProcessInfo.processInfo();
        let versionString = processInfo.operatingSystemVersionString().toString();
        let ver = versionString.split(' ');

        return ver[1];
    }
}