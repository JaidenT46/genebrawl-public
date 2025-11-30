import {LogicVector2} from "../../gene/battle/LogicVector2";
import {ProjectileData} from "../../gene/battle/ProjectileData";
import {UsefulInfo} from "../../gene/features/UsefulInfo";
import {Libg} from "../../libs/Libg";
import {LogicMath} from "../../titan/logic/math/LogicMath";
import {LogicProjectileData} from "../data/LogicProjectileData";
import {BattleMode} from "./BattleMode";
import {ClientInput, ClientInputType} from "./ClientInput";
import {ClientInputManager} from "./ClientInputManager";
import {LogicTileMap} from "./level/LogicTileMap";
import {LogicPlayer} from "./LogicPlayer";
import {LogicCharacterClientOwn} from "./objects/LogicCharacterClientOwn";
import {LogicGameObjectManagerClient} from "./objects/LogicGameObjectManagerClient";
import {LogicProjectileClient} from "./objects/LogicProjectileClient";

const LogicBattleModeClient_getOwnCharacter = new NativeFunction( // "spray_def_atk" (not sure)
    Libg.offset(0x9C4330, 0x4B7480), 'pointer', ['pointer']
);

const LogicBattleModeClient_update = new NativeFunction( // TODO
    Libg.offset(0x0, 0x4B5EA4), 'void', ['pointer', 'float', 'float']
);

const LogicBattleModeClient_ownPlayerIndexOffset = 224;
const LogicBattleModeClient_ownPlayerTeamOffset = 228;
const LogicBattleModeClient_tileMapOffset = 248;
const LogicBattleModeClient_currentBattleStateOffset = 284;
export const LogicBattleModeClient_gameModeVariationOffset = 292;
export const LogicBattleModeClient_underdogOffset = 334;

export class LogicBattleModeClient {
    static self: LogicBattleModeClient;

    private instance: NativePointer;
    private bulletXY!: number[][];
    private tileMap: LogicTileMap;
    private ticksGone: number = 0;
    private projectileGameObjectManager: LogicGameObjectManagerClient;

    constructor(instance: NativePointer) {
        this.instance = instance;

        this.tileMap = new LogicTileMap(
            instance.add(LogicBattleModeClient_tileMapOffset).readPointer()
        );

        this.projectileGameObjectManager = new LogicGameObjectManagerClient(
            this.instance.add(40).readPointer() // todo check other values like 48 or 56
        );

        LogicBattleModeClient.self = this;
    }

    tick() {
        this.ticksGone = this.instance.add(72).readInt();

        UsefulInfo.ticks = this.ticksGone;

        if (this.isGameOver()) {
            return;
        }
    }

    getOwnPlayerTeam() {
        return LogicBattleModeClient.getOwnPlayerTeam(this.instance);
    }

    getOwnPlayer() {
        return this.getPlayer(LogicBattleModeClient.getOwnPlayerIndex(this.instance));
    }

    isGameOver() {
        return this.instance.add(LogicBattleModeClient_currentBattleStateOffset).readInt() !== -1;
    }

    findBulletXY(globalId: number): number[] | undefined {
        return this.bulletXY.find(x => x[0] == globalId);
    }

    pushBulletXY(globalId: number, x: number, y: number): void {
        this.bulletXY.push([globalId, x, y]);
    }

    getPlayer(index: number): LogicPlayer {
        return LogicBattleModeClient.getPlayer(this.instance, index);
    }

    static getPlayer(self: NativePointer, index: number): LogicPlayer {
        return new LogicPlayer(
            self.readPointer().add(Process.pointerSize * index).readPointer()
        );
    }

    static getGameObjects(logicBattleModeClient: NativePointer) {
        return logicBattleModeClient.readPointer();
    }

    static getOwnCharacter(logicBattleModeClient: NativePointer): NativePointer {
        return LogicBattleModeClient_getOwnCharacter(logicBattleModeClient);
    }

    static getOwnPlayerIndex(logicBattleModeClient: NativePointer): number {
        return logicBattleModeClient.add(LogicBattleModeClient_ownPlayerIndexOffset).readInt();
    }

    static getOwnPlayerTeam(logicBattleModeClient: NativePointer): number {
        return logicBattleModeClient.add(LogicBattleModeClient_ownPlayerTeamOffset).readInt();
    }

    static getTileMap(logicBattleModeClient: NativePointer): LogicTileMap {
        return new LogicTileMap(
            logicBattleModeClient.add(LogicBattleModeClient_tileMapOffset).readPointer()
        );
    }

    static isUnderdog(self: NativePointer): boolean {
        return Boolean(self.add(LogicBattleModeClient_underdogOffset).readU8());
    }

    static patch() {
        Interceptor.replace(LogicBattleModeClient_update, new NativeCallback(function (battleModeClient, a1, a2) {
            LogicBattleModeClient_update(battleModeClient, a1, a2);

            if (!LogicBattleModeClient.self || !LogicBattleModeClient.self.instance.equals(battleModeClient)) {
                new LogicBattleModeClient(battleModeClient);
            }

            // ain't we already

            LogicBattleModeClient.self.tick();
        }, 'void', ['pointer', 'float', 'float']));
    }
}