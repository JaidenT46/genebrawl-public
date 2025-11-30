    import {GradientNickname} from "../../gene/features/GradientNickname";
import {Libg} from "../../libs/Libg";
import {HashTagCodeGenerator} from "../../titan/logic/util/HashTagCodeGenerator";

const AllianceHeaderEntry_decode = new NativeFunction( // 24399 decode
    Libg.offset(0x969BD0, 0x478CE8), 'void', ['pointer', 'pointer']
);

const AllianceHeaderEntry_nameOffset = 8;

export class AllianceHeaderEntry {
    instance: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
    }

    getAllianceId() {
        return AllianceHeaderEntry.getAllianceId(this.instance);
    }

    getAllianceName() {
        return AllianceHeaderEntry.getAllianceName(this.instance);
    }

    static getAllianceId(self: NativePointer): NativePointer {
        return self.readPointer();
    }

    static getAllianceName(self: NativePointer): string {
        return self.add(AllianceHeaderEntry_nameOffset).readPointer().fromsc();
    }

    static patch() {
        Interceptor.replace(AllianceHeaderEntry_decode, new NativeCallback(function (self, byteStream) {
            AllianceHeaderEntry_decode(self, byteStream);

            const allianceIdPtr = AllianceHeaderEntry.getAllianceId(self);

            const allianceName = self.add(AllianceHeaderEntry_nameOffset).readPointer();
            const allianceTag = HashTagCodeGenerator.toCode(allianceIdPtr);

            GradientNickname.setClubGradient(allianceTag, allianceName);
        }, 'void', ['pointer', 'pointer']));
    }
}