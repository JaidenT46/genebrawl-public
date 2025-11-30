import {LocalizationManager} from "../index";
import {Change} from "./Change";

interface IChanges {
    additions?: Change[],
    fixes?: Change[],
    removals?: Change[];
}

export class ChangeLog {
    releaseDate: string = ""; // please use YYYY.MM.DD type (2024.12.31)
    scriptVersion: number = 0;

    shortDesc: string = "";

    additions: Change[] = [];
    fixes: Change[] = [];
    removes: Change[] = [];

    private logs: string[] = [];

    constructor(releaseDate: string, scriptVersion: number, shortDesc: string, changes?: IChanges) {
        this.releaseDate = releaseDate;
        this.scriptVersion = scriptVersion;
        this.shortDesc = shortDesc;
        this.additions = changes?.additions || [];
        this.fixes = changes?.fixes || [];
        this.removes = changes?.removals || [];
    }

    build() {
        this.logs = [];

        this.addNewLine(`${this.releaseDate} - ${LocalizationManager.getString("CHANGELOGS_SCRIPTVERSION").replace("{scriptVersion}", this.scriptVersion.toString())}`);
        if (this.shortDesc.length > 0) this.addNewLine(this.shortDesc);
        if (this.additions.length > 0) this.addNewLine(`${LocalizationManager.getString("CHANGELOGS_ADDITIONS")}:\n${this.additions.map(e => e.build()).join("\n")}`);
        if (this.fixes.length > 0) this.addNewLine(`${LocalizationManager.getString("CHANGELOGS_FIXES")}:\n${this.fixes.map(e => e.build()).join("\n")}`);
        if (this.removes.length > 0) this.addNewLine(`${LocalizationManager.getString("CHANGELOGS_REMOVALS")}:\n${this.removes.map(e => e.build()).join("\n")}`);

        return this.logs.join("\n");
    }

    addNewLine(line: string) {
        this.logs.push(line);
        this.logs.push("");
    }
}

/*
new ChangeLog(
    "31.12.2099",
    69,
    "something new",
    [
        new Change("New function", "Hell nah this is a new FUNCTION???")
    ],
    [
        new Change("Fixed something", "Now it's fixed. Hopefully")
    ],
    []
)
*/