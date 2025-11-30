import {Libg} from "../../../libs/Libg";

const CSVRow_getName = new NativeFunction( // "IconSWF" in LogicData::setCSVRow last func
    Libg.offset(0xA9158C, 0x9EB178), 'pointer', ['pointer']
);

export class CSVRow {
    static getName(csvRow: NativePointer): NativePointer {
        return CSVRow_getName(csvRow);
    }
}
