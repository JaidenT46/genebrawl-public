import {GradientNickname} from "../../gene/features/GradientNickname";
import {Libg} from "../../libs/Libg";
import {HashTagCodeGenerator} from "../../titan/logic/util/HashTagCodeGenerator";
import {LogicHeroConfiguration} from "./LogicHeroConfiguration";
import {LogicPlayerTitleData} from "../data/LogicPlayerTitleData";
import {LogicDataTables} from "../data/LogicDataTables";
import {GlobalID} from "../data/GlobalID";
import {LogicCharacterData} from "../data/LogicCharacterData";

const LogicPlayer_decode = new NativeFunction( // 20559 decode
    Libg.offset(0x9EAB50, 0x4CA608), 'void', ['pointer', 'pointer']
);

export const battleCard_titleOffset = 40;
export const battleCard = 440;

const LogicPlayer_PlayerDisplayDataOffset = 448;
const logicAccessoryOffset = 280;
const playerIndexOffset = 8;
const teamIndexOffset = 12;
const characterGlobalIdOffset = 16;
const heroesOffset = 48;
const heroesCountOffset = 60;

const ultiCountOffset = 84;
const maxUltiCountOffset = 88;
const overChargeCountOffset = 100;

export class LogicPlayer {
    instance: NativePointer;

    constructor(instance: NativePointer) {
        this.instance = instance;
    }

    getAvatarId() {
        return this.instance.accountId();
    }

    getName(): string {
        return this.getPlayerDisplayData().fromsc();
    }

    getTeamIndex(): number {
        return this.instance.add(teamIndexOffset).readInt();
    }

    hasUlti() {
        return this.instance.add(ultiCountOffset).readInt() === this.instance.add(maxUltiCountOffset).readInt();
    }

    isBot() {
        return LogicPlayer.isBot(this.instance);
    }

    isOwnPlayerTeam(team: number): boolean {
        return this.getTeamIndex() == team;
    }

    getHero(index: number) {
        return this.getHeroes().add(Process.pointerSize * index).readPointer();
    }

    getHeroes() {
        return LogicPlayer.getHeroes(this.instance);
    }

    getHeroesCount() {
        return LogicPlayer.getHeroesCount(this.instance);
    }

    getHashTag() {
        return LogicPlayer.getHashTag(this.instance);
    }

    getPlayerDisplayData() {
        return LogicPlayer.getPlayerDisplayData(this.instance);
    }

    getCharacterData(index: number) {
        return new LogicCharacterData(this.getHero(index).readPointer());
    }

    getPlayerIndex(): number {
        return LogicPlayer.getPlayerIndex(this.instance);
    }

    getCharacterGlobalId(): number {
        return LogicPlayer.getCharacterGlobalId(this.instance);
    }

    getTitle() {
        return LogicPlayer.getTitle(this.instance);
    }

    setTitle(dataRef: NativePointer) {
        LogicPlayer.setTitle(this.instance, dataRef);
    }

    setName(name: string) {
        this.getPlayerDisplayData().scptr(name);
    }

    toString(): string {
        let result = `• ${this.getName()} (#${this.getHashTag()}) `;
        let heroesCount = this.getHeroesCount();
        if (heroesCount > 1) {
            result += "\n    ";
        }

        for (let index = 0; index < this.getHeroesCount(); index++) {
            if (index > 0) {
                result += "\n    ";
            }
            const hero = this.getHero(index);
            result += LogicHeroConfiguration.toString(hero);
        }

        return result;
    }

    static patch() {
        const self = this;

        Interceptor.replace(LogicPlayer_decode, new NativeCallback(function (logicPlayer, byteStream) {
            LogicPlayer.decode(logicPlayer, byteStream);

            const playerTag = HashTagCodeGenerator.toCode(logicPlayer);
            if (logicPlayer.add(battleCard).readPointer().isNull())
                return;

            const playerDisplayData = self.getPlayerDisplayData(logicPlayer);

            if (GradientNickname.doPlayerHaveTitle(playerTag)) {
                let dataRef = new LogicPlayerTitleData(LogicDataTables.getByGlobalId(GlobalID.createGlobalID(76, 83)));

                self.setTitle(logicPlayer, dataRef.instance);

                const instanceId = 1000 + GradientNickname.getPlayerTitleIndex(playerTag);
                dataRef.setGlobalID(GlobalID.createGlobalID(76, instanceId));
            }

            GradientNickname.setPlayerGradient(playerTag, playerDisplayData);
        }, 'void', ['pointer', 'pointer']));
    }

    static decode(logicPlayer: NativePointer, ByteStream: NativePointer) {
        LogicPlayer_decode(logicPlayer, ByteStream);
    }

    static getAvatarId(logicPlayer: NativePointer) {
        return logicPlayer.accountId();
    }

    static getName(logicPlayer: NativePointer): string {
        return LogicPlayer.getPlayerDisplayData(logicPlayer).fromsc();
    }

    static hasUlti(logicPlayer: NativePointer): boolean {
        return logicPlayer.add(ultiCountOffset).readInt() == logicPlayer.add(maxUltiCountOffset).readInt();
    }

    static hasOvercharge(logicPlayer: NativePointer): boolean {
        return logicPlayer.add(overChargeCountOffset).readInt() == logicPlayer.add(maxUltiCountOffset).readInt();
    }

    static isBot(logicPlayer: NativePointer) {
        return this.getName(logicPlayer).length == 1;
    }

    static getCharacterGlobalId(logicPlayer: NativePointer): number {
        return logicPlayer.add(characterGlobalIdOffset).readInt();
    }

    static getHashTag(logicPlayer: NativePointer) {
        return LogicPlayer.isBot(logicPlayer) ? "0" : HashTagCodeGenerator.toCode(logicPlayer);
    }

    static getHeroes(logicPlayer: NativePointer) {
        return logicPlayer.add(heroesOffset).readPointer();
    }

    static getHeroesCount(logicPlayer: NativePointer) {
        return logicPlayer.add(heroesCountOffset).readInt();
    }

    static getHero(logicPlayer: NativePointer, index: number) {
        return LogicPlayer.getHeroes(logicPlayer).add(Process.pointerSize * index).readPointer();
    }

    static getPlayerDisplayData(logicPlayer: NativePointer): NativePointer {
        return logicPlayer.add(battleCard).readPointer().readPointer();
    }

    static getTitle(logicPlayer: NativePointer): NativePointer {
        return logicPlayer.add(battleCard).readPointer().add(battleCard_titleOffset).readPointer();
    }

    static setTitle(logicPlayer: NativePointer, title: NativePointer) {
        logicPlayer.add(battleCard).readPointer().add(battleCard_titleOffset).writePointer(title);
    }

    static toString(logicPlayer: NativePointer): string {
        let result: string = `• ${this.getName(logicPlayer)} (#${HashTagCodeGenerator.toCode(logicPlayer)}) `;

        const heroes = this.getHeroes(logicPlayer);

        for (let j = 0; j < logicPlayer.add(heroesCountOffset).readInt(); j++) {
            const hero = heroes.add(Process.pointerSize * j).readPointer();
            result += LogicHeroConfiguration.toString(hero);
        }

        return result;
    }

    static getPlayerIndex(playerPtr: NativePointer) {
        return playerPtr.add(playerIndexOffset).readInt();
    }

    getAccessory() {
        return this.instance.add(logicAccessoryOffset).readPointer();
    }

    static getAccessory(playerPtr: NativePointer) {
        return playerPtr.add(logicAccessoryOffset).readPointer();
    }
}