import {Libg} from "../../libs/Libg";

const SoundManager_instance = Libg.offset(0x103E7E0, 0xEE6718); // "stopMusic" string, then qword in xref

const SoundManager_playMusic = new NativeFunction( // "Trying to play disabled music %s"
    Libg.offset(0x7FB1EC, 0x362794), 'void', ['pointer', 'pointer']
);

export class SoundManager {
    static get instance(): NativePointer {
        return SoundManager_instance.readPointer();
    }

    static playMusic(musicData: NativePointer) {
        SoundManager_playMusic(this.instance, musicData);
    }
}