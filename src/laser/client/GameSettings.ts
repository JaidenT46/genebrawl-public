import {Libg} from "../../libs/Libg";

// Static instances
const GameSettings_instance = Libg.offset(0x0, 0xEE6708);

// Fields
const isSfxEnabledOffset = 8;
const isMusicEnabledOffset = 12;
const isHapticsEnabledOffset = 16;

// Native functions
// InitFunc "HapticsDisabled"

const GameSettings_enableSfx = new NativeFunction( // TODO
    Libg.offset(-1, 0x35B8F0), 'void', ['pointer', 'int']
);

const GameSettings_enableMusic = new NativeFunction(
    Libg.offset(-1, 0x35B7E8), 'void', ['pointer', 'int']
);

const GameSettings_enableHaptics = new NativeFunction(
    Libg.offset(0x7F34B8, 0x35B96C), 'void', ['pointer', 'int'] // "haptics_toggle"
);

export class GameSettings {
    static get instance(): NativePointer {
        return GameSettings_instance.readPointer();
    }

    static get sfxEnabled(): boolean {
        return Boolean(
            this.instance.add(isSfxEnabledOffset).readU8()
        );
    }

    static get musicEnabled(): boolean {
        return Boolean(
            this.instance.add(isMusicEnabledOffset).readU8()
        );
    }

    static get hapticsEnabled(): boolean {
        return Boolean(
            this.instance.add(isHapticsEnabledOffset).readU8()
        );
    }

    static set sfxEnabled(enabled: boolean) {
        GameSettings_enableSfx(this.instance, enabled ? 100 : 0);
    }

    static set musicEnabled(enabled: boolean) {
        GameSettings_enableMusic(this.instance, enabled ? 100 : 0);
    }

    static set hapticsEnabled(enabled: boolean) {
        GameSettings_enableHaptics(this.instance, Number(enabled));
    }
}