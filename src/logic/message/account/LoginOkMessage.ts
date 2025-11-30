import {PiranhaMessage} from "../PiranhaMessage";

const accountIdOffset = 144;
const serverMajorOffset = 200;
const serverBuildOffset = 204;
const serverMinorOffset = 208;
const serverEnvironmentOffset = 216;
const sessionCountOffset = 224;
const playtimeSecondsOffset = 228;
const daysSinceStartedPlayingOffset = 232;
const accountTierOffset = 320;

export class LoginOkMessage extends PiranhaMessage {
    getAccountId(): number[] {
        return this.instance.add(accountIdOffset).readPointer().accountId();
    }

    getServerVersion(): string {
        return `${this.instance.add(serverMajorOffset).readInt()}.${this.instance.add(serverBuildOffset).readInt()}.${this.instance.add(serverMinorOffset).readInt()}`;
    }

    getServerEnvironment(): string {
        return this.instance.add(serverEnvironmentOffset).readPointer().fromsc();
    }

    getSessionCount(): number {
        return this.instance.add(sessionCountOffset).readInt();
    }

    getPlaytimeSeconds(): number {
        return this.instance.add(playtimeSecondsOffset).readInt();
    }

    getDaysSinceStartedPlaying(): number {
        return this.instance.add(daysSinceStartedPlayingOffset).readInt();
    }

    getAccountTier(): number {
        return this.instance.add(accountTierOffset).readInt();
    }
}