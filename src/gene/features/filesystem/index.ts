import {Libc} from "../../../libs/Libc";
import {Path} from "../../../titan/Path";

type FileData = ArrayBuffer | string | Uint8Array;

export class Filesystem {
    static writeToFile(path: string, data: FileData) {
        try {
            if (data instanceof Uint8Array) {
                data = data.buffer as ArrayBuffer;
            }

            const splitPath = path.split("/");
            Filesystem.createDirectoryIfNotExist(Path.getUpdatePath() + splitPath[splitPath.length - 2] + "/");

            const file = new File(path, "w");

            file.write(data);

            file.close();
        } catch (e) {
            console.error(e);
        }
    }

    static readDirectory(directory: string) {
        const dir = Libc.opendir(directory);
        const content: string[] = [];

        if (dir.isNull()) return content;

        let dirent = Libc.readdir(dir);

        while (!dirent.isNull()) {
            const dName = dirent.add(19).readUtf8String();
            const dType = dirent.add(18).readU8();

            if (!dName?.startsWith(".")) {
                content.push(dName!);
            }

            dirent = Libc.readdir(dir);
        }

        Libc.closedir(dir);

        return content;
    }

    static doesFileExist(path: string) {
        try {
            const file = new File(path, 'r');

            file.close();

            return true;
        } catch (e) {
            return false;
        }
    }

    static readFile(path: string) {
        try {
            const file = new File(path, 'r');

            const content = file.readBytes();

            file.close();

            return content;
        } catch (e) {
            return null;
        }
    }

    static isDirectory(path: string) {
        try {
            const file = new File(path, 'w');

            file.close();

            return false;
        } catch (e: any) {
            return e.message.includes("Is a directory");
        }
    }

    static createDirectoryIfNotExist(path: string) {
        const directories = path.split("/");

        for (let i = 0; i < directories.length; i++) {
            const mergedPath = directories.slice(0, i).join("/");
            if (mergedPath.length === 0) continue;
            if (Libc.access(mergedPath) === -1) {
                Path.mkdir(mergedPath);
            }
        }
    }

    static removeFile(path: string) {
        return Libc.remove(path);
    }
}