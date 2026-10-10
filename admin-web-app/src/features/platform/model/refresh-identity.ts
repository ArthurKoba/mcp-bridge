import { platformPort } from "@/features/platform/api/port"
import { projectContext } from "@/features/platform/model/project-context"
import { refreshBffOwnerBoundary } from "@/features/platform/model/refresh-owner-boundary"
import type { PlatformPort } from "@/features/platform/model/contracts"

interface ProjectionRefresh {
  port: PlatformPort
  actor: string
  revision: number
  controller: AbortController
  promise: Promise<void>
}
let inFlight: ProjectionRefresh | null = null

/**
 * One source-backed principal/permission refresh per verified UI generation.
 * Multiple components may request it after one Team/Project mutation, but
 * concurrent A4 bearer-rotation calls must never invalidate each other.
 */
export function refreshAuthenticatedProjection(): Promise<void> {
  const port=platformPort.value
  const actor=projectContext.state.user?.key
  if(!port||!actor)return Promise.resolve()
  const revision=projectContext.state.revision
  if(inFlight && inFlight.port===port && inFlight.actor===actor && inFlight.revision===revision) {
    return inFlight.promise
  }
  inFlight?.controller.abort()
  const controller=new AbortController()
  const cancelOnTransition=projectContext.onTransition(()=>controller.abort())
  const refresh = (async()=>{
    try {
      const projection=await port.auth.refresh(controller.signal)
      if(controller.signal.aborted||port!==platformPort.value||revision!==projectContext.state.revision||actor!==projectContext.state.user?.key)return
      if(!projection||!projection.user.active||projection.user.userId!==actor){
        projectContext.clear()
        return
      }
      projectContext.installServerProjection(projection)
      await refreshBffOwnerBoundary()
    } catch {
      if(!controller.signal.aborted&&port===platformPort.value&&revision===projectContext.state.revision&&actor===projectContext.state.user?.key) {
        // Unverified stale permission projections cannot stay actionable.
        projectContext.offline()
      }
    } finally {
      cancelOnTransition()
      if(inFlight?.controller===controller)inFlight=null
    }
  })()
  inFlight={port,actor,revision,controller,promise:refresh}
  return refresh
}
