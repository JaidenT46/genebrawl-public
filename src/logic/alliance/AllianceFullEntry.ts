import {AllianceHeaderEntry} from "./AllianceHeaderEntry";

export class AllianceFullEntry {
    instance: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
    }

    getAllianceHeaderEntry() {
        return AllianceFullEntry.getAllianceHeaderEntry(this.instance);
    }

    static getAllianceHeaderEntry(self: NativePointer): AllianceHeaderEntry {
        return new AllianceHeaderEntry(
            self.readPointer()
        );
    }
}