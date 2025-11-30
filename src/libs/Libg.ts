import {LogicDefines} from "../LogicDefines";
import {Libc} from "./Libc";

const gameLibraryName = LogicDefines.isPlatformIOS() ? "laser" : "libg.so";

export class Libg {
    static module: Module;
    static size: number;
    static begin: NativePointer;
    static end: NativePointer;

    static init(path: string): void {
        this.module = Process.findModuleByName(path)!;
        this.begin = this.module.base;
        this.size = this.module.size;
        this.end = this.begin.add(this.size);
    }

    static offset(android_arm64: number, ios: number): NativePointer {
        if (!this.module)
            this.init(gameLibraryName);

        let offset = LogicDefines.isPlatformAndroid() ? android_arm64 : ios;
        if (offset == -1) {
            return Libc.malloc(8); // ignore
        }

        if (offset < 0x3) {
            console.error(new Error(`Libg.offset - offset is NULL! Please update it. (${LogicDefines.toString()})`).stack);
            return Libc.malloc(8);
        }

        return this.begin.add(offset);
    }
}