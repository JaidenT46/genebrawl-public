import {Libg} from "../../../libs/Libg";
import {StreamItemList} from "./StreamItemList";

const TeamStream_update = new NativeFunction(
    Libg.offset(0x5020E8, 0xE25D4), 'void', ['pointer', 'float'] // "TID_CLAN_CHAT_JUMP_TO_NEW"
);

const TeamStream_instance = Libg.offset(0x103D9B0, 0xEE6208);

const TeamStream_StreamItemListOffset = 136;

export class TeamStream {
    static getInstance() {
        return TeamStream_instance.readPointer();
    }

    static update(time: number) {
        TeamStream_update(TeamStream.getInstance(), time);
    }

    static getLastItem() {
        if (TeamStream.getInstance().isNull()) return NULL;

        return StreamItemList.getLastItem(TeamStream.getInstance().add(TeamStream_StreamItemListOffset).readPointer());
    }
}
