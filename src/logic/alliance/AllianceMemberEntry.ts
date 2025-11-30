import {GradientNickname} from "../../gene/features/GradientNickname";
import {Libg} from "../../libs/Libg";
import {HashTagCodeGenerator} from "../../titan/logic/util/HashTagCodeGenerator";

const AllianceMemberEntry_decode = new NativeFunction( // 24308 decode
    Libg.offset(0x96A528, 0x4794AC), 'void', ['pointer', 'pointer']
);

const AllianceMemberEntry_IDOffset = 40;
const AllianceMemberEntry_PlayerDisplayDataOffset = 56;

export class AllianceMemberEntry {
    static patch() {
        Interceptor.replace(AllianceMemberEntry_decode, new NativeCallback(function (allianceMemberEntry, ByteStream) {
            AllianceMemberEntry_decode(allianceMemberEntry, ByteStream);

            const memberId = allianceMemberEntry.add(AllianceMemberEntry_IDOffset).readPointer();
            const memberTag = HashTagCodeGenerator.toCode(memberId);

            const playerDisplayData = allianceMemberEntry.add(AllianceMemberEntry_PlayerDisplayDataOffset).readPointer();

            GradientNickname.setPlayerGradient(memberTag, playerDisplayData);
        }, 'void', ['pointer', 'pointer']));
    }
}