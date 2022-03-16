'use strict'

import * as vscode from 'vscode'
import * as request from 'request'

const timerInterval = 200

type Task = {
  isPending: boolean
  isQueueing: boolean
  lastExecutedTime: number
}

type Doc = {
  task: Task
  diagnosticCollection: vscode.DiagnosticCollection
}

type RequestOptions = {
  method: string
  url: string
  strictSSL: boolean
  auth?: {
    user: string
    pass: string
  }
  formData?: Record<string, string>
  headers?: Record<string, string>
}

const docMap = new Map<string, Doc>()

const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms))

const registerDoc = (doc?: vscode.TextDocument) => {
  if (!/[\\\/]Jenkinsfile/.test(doc?.fileName ?? '')) {
    return
  }
  const id = doc?.uri.fsPath ?? ''
  if (!docMap.has(id)) {
    docMap.set(id, {
      diagnosticCollection: vscode.languages.createDiagnosticCollection('Jenkinsfile'),
      task: {
        isPending: false,
        isQueueing: false,
        lastExecutedTime: 0
      }
    })
  }
  return true
}

export function activate(context: vscode.ExtensionContext) {
  const output = vscode.window.createOutputChannel('Jenkins Pipeline Linter')
  let lastInput: string | undefined

  const _validateJenkinsfile = async (doc: vscode.TextDocument) => {
    if (doc.isClosed) return
    const config = vscode.workspace.getConfiguration()
    let url = config.get<string>('jenkins.pipeline.linter.connector.url') || lastInput
    let user = config.get<string>('jenkins.pipeline.linter.connector.user')
    let pass = config.get<string>('jenkins.pipeline.linter.connector.pass')
    let token = config.get<string>('jenkins.pipeline.linter.connector.token')
    let crumbUrl = config.get<string>('jenkins.pipeline.linter.connector.crumbUrl')
    let strictssl = config.get<boolean>('jenkins.pipeline.linter.connector.strictssl')!

    if (url === undefined || url.length === 0) {
      url = await vscode.window.showInputBox({ prompt: 'Enter Jenkins Pipeline Linter Url.', value: lastInput })
    }
    if (
      user !== undefined &&
      user.length > 0 &&
      (pass === undefined || pass.length === 0) &&
      (token === undefined || token.length === 0)
    ) {
      pass = await vscode.window.showInputBox({ prompt: 'Enter password.', password: true })
      if (pass === undefined || pass.length === 0) {
        token = await vscode.window.showInputBox({ prompt: 'Enter token.', password: false })
      }
    }
    if (url !== undefined && url.length > 0) {
      lastInput = url

      if (crumbUrl !== undefined && crumbUrl.length > 0) {
        requestCrumb(doc, url, crumbUrl, user, pass, token, strictssl, output)
      } else {
        validateRequest(doc, url, user, pass, token, undefined, strictssl, output)
      }
    } else {
      output.appendLine('Jenkins Pipeline Linter Url is not defined.')
    }
    output.show(true)
  }

  const validateJenkinsfile = async (doc: vscode.TextDocument) => {
    if (docMap.has(doc.uri.fsPath)) {
      const model = docMap.get(doc.uri.fsPath)!
      if (model.task.isPending) {
        if (!model.task.isQueueing) {
          model.task.isQueueing = true
        }
        return
      } else {
        model.task.isPending = true
        if (Date.now() - model.task.lastExecutedTime < timerInterval) {
          await sleep(Date.now() - model.task.lastExecutedTime).then(() => _validateJenkinsfile(doc))
        } else {
          await _validateJenkinsfile(doc)
        }
        if (!doc.isClosed) {
          model.task.isPending = false
          model.task.lastExecutedTime = Date.now()
          if (model.task.isQueueing) {
            model.task.isQueueing = false
            validateJenkinsfile(doc)
          }
        }
      }
    }
  }

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      registerDoc(doc)
    }),
    vscode.workspace.onDidChangeTextDocument((e) => {
      validateJenkinsfile(e.document)
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      if (docMap.has(doc.uri.fsPath)) {
        docMap.delete(doc.uri.fsPath)
      }
    })
  )
}

function requestCrumb(
  doc: vscode.TextDocument,
  url: string,
  crumbUrl: string,
  user: string | undefined,
  pass: string | undefined,
  token: string | undefined,
  strictssl: boolean,
  output: vscode.OutputChannel
) {
  const options: RequestOptions = {
    method: 'GET',
    url: crumbUrl,
    strictSSL: strictssl
  }

  if (user !== undefined && user.length > 0) {
    if (pass !== undefined && pass.length > 0) {
      options.auth = {
        user: user,
        pass: pass
      }
    } else if (token !== undefined && token.length > 0) {
      const authToken = Buffer.from(user + ':' + token).toString('base64')
      options.headers = Object.assign(options.headers, { Authorization: 'Basic ' + authToken })
    }
  }

  return new Promise((res) => {
    request(options, (err, _, body) => {
      res(err ? output.appendLine(err) : validateRequest(doc, url, user, pass, token, body, strictssl, output))
    })
  })
}

function parseOutput(res: string) {
  const matcher = /WorkflowScript:\s*\d+:\s*([\s\S]*?)\s*@\s*line\s*(\d+),\s*column\s*(\d+)/g
  const ret: { msg: string; pos: vscode.Position }[] = []
  let match: RegExpExecArray | null
  while ((match = matcher.exec(res))) {
    ret.push({
      msg: match[1],
      pos: new vscode.Position(Number(match[2]) - 1, Number(match[3]) - 1)
    })
  }
  return ret
}

function validateRequest(
  document: vscode.TextDocument | undefined,
  url: string,
  user: string | undefined,
  pass: string | undefined,
  token: string | undefined,
  crumb: string | undefined,
  strictssl: boolean,
  output: vscode.OutputChannel
) {
  output.clear()
  if (document) {
    const uri = document.uri
    const options: RequestOptions = {
      method: 'POST',
      url: url,
      strictSSL: strictssl,
      formData: {
        jenkinsfile: document.getText()
      },
      headers: {}
    }

    if (crumb !== undefined && crumb.length > 0) {
      const crumbSplit = crumb.split(':')
      options.headers = Object.assign(options.headers, { 'Jenkins-Crumb': crumbSplit[1] })
    }

    if (user !== undefined && user.length > 0) {
      if (pass !== undefined && pass.length > 0) {
        options.auth = {
          user: user,
          pass: pass
        }
      } else if (token !== undefined && token.length > 0) {
        const authToken = new Buffer(user + ':' + token).toString('base64')
        options.headers = Object.assign(options.headers, { Authorization: 'Basic ' + authToken })
      }
    }

    return new Promise((res) => {
      request(options, (err, _, body) => {
        if (document.isClosed) return
        if (err) {
          output.appendLine(err)
        } else {
          docMap.get(uri.fsPath)?.diagnosticCollection.set(
            uri,
            parseOutput(body).map(
              (item) =>
                new vscode.Diagnostic(new vscode.Range(item.pos, item.pos), item.msg, vscode.DiagnosticSeverity.Error)
            )
          )
          output.appendLine(body)
        }
        res(undefined)
      })
    })
  } else {
    output.appendLine('No active text editor. Open the jenkinsfile you want to validate.')
  }
}

// this method is called when your extension is deactivated
export function deactivate() {}
