import {SkinChanger} from "../../../gene/features/SkinChanger";
import {Libg} from "../../../libs/Libg";

const TeamEntry_decode = new NativeFunction( // 24124 decode
    Libg.offset(0x96D890, 0x47BB70), 'void', ['pointer', 'pointer']
);

const TeamEntry_TeamMemberArrayOffset = 48;

export class TeamEntry {
    static patch() {
        Interceptor.replace(TeamEntry_decode, new NativeCallback(function (teamEntry, byteStream) {
            TeamEntry_decode(teamEntry, byteStream);

            SkinChanger.patchTeamEntry(teamEntry.add(TeamEntry_TeamMemberArrayOffset).readPointer());
        }, 'void', ['pointer', 'pointer']));
    }
}