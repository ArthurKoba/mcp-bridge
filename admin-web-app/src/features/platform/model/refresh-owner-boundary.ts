import { watch } from "vue"
import { projectContext } from "@/features/platform/model/project-context"
import { platformPort } from "@/features/platform/api/port"
import type { QueryContext, ScopeSelection } from "@/features/platform/model/contracts"
import { sameBffScope } from "@/features/platform/api/bff-boundary"

/** One server-authenticated BFF read per actor/scope/revision. No client
 * guessing of PostgreSQL, Alembic heads, backend hosts or owner credentials. */
interface ActiveRead {
  readonly port: NonNullable<typeof platformPort.value>
  readonly actor:string
  readonly revision:number
  readonly scope:ScopeSelection
  readonly controller:AbortController
  readonly promise:Promise<boolean>
}
let active:ActiveRead|null=null

export function refreshBffOwnerBoundary():Promise<boolean>{
  const port=platformPort.value
  const actor=projectContext.state.user?.key
  const scope=projectContext.selection()
  if(!port?.bff||!actor||!scope||!projectContext.state.user?.active){
    active?.controller.abort()
    active=null
    projectContext.ownerUnavailable()
    return Promise.resolve(false)
  }
  const revision=projectContext.state.revision
  if(active&&active.port===port&&active.actor===actor&&active.revision===revision&&
     sameBffScope(active.scope,scope))return active.promise
  active?.controller.abort()
  const controller=new AbortController()
  const detach=projectContext.onTransition(()=>controller.abort())
  const stop=watch(platformPort,()=>controller.abort())
  projectContext.ownerLoading()
  const context:QueryContext={
    scope,signal:controller.signal,revision,
    decisionVersion:scope.kind==="project"?projectContext.state.projectDecisionVersions[scope.projectId]??null:
      scope.kind==="team"?projectContext.state.teamDecisionVersions[scope.teamId]??null:null,
  }
  const pending=(async():Promise<boolean>=>{
    try {
      const evidence=await port.bff!.current(context)
      const selected=projectContext.selection()
      if(controller.signal.aborted||port!==platformPort.value||
         revision!==projectContext.state.revision||projectContext.state.user?.key!==actor||
         !selected||!sameBffScope(selected,scope))return false
      return projectContext.installOwnerEvidence(evidence)
    }catch{
      if(!controller.signal.aborted&&port===platformPort.value&&
         revision===projectContext.state.revision&&projectContext.state.user?.key===actor){
        // Failure of Identity/Access/Control verification may NOT be replaced
        // with a cached read-side projection or a fake positive health check.
        projectContext.ownerUnavailable()
      }
      return false
    }finally{
      detach();stop()
      if(active?.controller===controller)active=null
    }
  })()
  active={port,actor,revision,scope,controller,promise:pending}
  return pending
}
