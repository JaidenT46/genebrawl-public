import {GradientNickname} from "../../gene/features/GradientNickname";
import {Libg} from "../../libs/Libg";
import {HashTagCodeGenerator} from "../../titan/logic/util/HashTagCodeGenerator";

const FriendEntry_decode = new NativeFunction(
    Libg.offset(0x984294, 0x48C3A0), 'void', ['pointer', 'pointer'] // 20105 decode
);

const FriendEntry_PlayerDisplayDataOffset = 144;

export class FriendEntry {
    static patch() {
        Interceptor.replace(FriendEntry_decode, new NativeCallback(function (friendEntry, ByteStream) {
            FriendEntry_decode(friendEntry, ByteStream);

            const playerId = friendEntry.readPointer();
            const playerTag = HashTagCodeGenerator.toCode(playerId);

            const playerDisplayData = friendEntry.add(FriendEntry_PlayerDisplayDataOffset).readPointer();

            if (playerDisplayData.isNull()) return;

            try {
                GradientNickname.setPlayerGradient(playerTag, playerDisplayData);
            } catch (e) {
                console.error("FriendEntry::decode:", "exception while setting player gradient: " + e);
            }
        }, 'void', ['pointer', 'pointer']));
    }
}