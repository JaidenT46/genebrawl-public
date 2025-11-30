export class Change {
    private name: string = "";
    private desc: string = "";

    constructor(name: string, desc?: string) {
        this.name = name;
        this.desc = desc || "";
    }

    build() {
        return `- ${this.name}${this.desc.length > 0 ? `\n${this.desc}` : ""}`;
    }
}