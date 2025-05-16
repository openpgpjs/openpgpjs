/**
 * The config module cannot be written in TS directly for now,
 * since our JSDoc compiler does not support TS.
 */
import config, { type Config } from './config';


// PartialConfig has the same properties as Config, but declared as optional.
// This interface is relevant for top-level functions, which accept a subset of configuration options
interface PartialConfig extends Partial<Config> {}

export { Config, PartialConfig };
export default config;
