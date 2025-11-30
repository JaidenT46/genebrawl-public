
export class LogicDefines {
    static isPlatformIOS(): boolean {
        return Process.platform == "darwin";
    }

    static isPlatformAndroid(): boolean {
        return Process.platform == "linux";
    }

    static toString(): string {
        return `${this.isPlatformAndroid() ? "Android" : "iOS"} ${Process.arch.toUpperCase()}`;
    }
}
